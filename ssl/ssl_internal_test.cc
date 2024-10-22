/* Copyright (c) 2024, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <gtest/gtest.h>

#include <openssl/ssl.h>

#include "internal.h"


#if !defined(BORINGSSL_SHARED_LIBRARY)
BSSL_NAMESPACE_BEGIN
namespace {

TEST(ArrayTest, InitValueConstructs) {
  Array<uint8_t> array;
  ASSERT_TRUE(array.Init(10));
  EXPECT_EQ(array.size(), 10u);
  for (size_t i = 0; i < 10u; i++) {
    EXPECT_EQ(0u, array[i]);
  }
}

TEST(ArrayDeathTest, BoundsChecks) {
  Array<int> array;
  const int v[] = {1, 2, 3, 4};
  ASSERT_TRUE(array.CopyFrom(v));
  EXPECT_DEATH_IF_SUPPORTED(array[4], "");
}

TEST(VectorTest, Resize) {
  Vector<size_t> vec;
  ASSERT_TRUE(vec.empty());
  EXPECT_EQ(vec.size(), 0u);

  ASSERT_TRUE(vec.Push(42));
  ASSERT_TRUE(!vec.empty());
  EXPECT_EQ(vec.size(), 1u);

  // Force a resize operation to occur
  for (size_t i = 0; i < 16; i++) {
    ASSERT_TRUE(vec.Push(i + 1));
  }

  EXPECT_EQ(vec.size(), 17u);

  // Verify that expected values are still contained in vec
  for (size_t i = 0; i < vec.size(); i++) {
    EXPECT_EQ(vec[i], i == 0 ? 42 : i);
  }

  // Clearing the vector should give an empty one.
  vec.clear();
  ASSERT_TRUE(vec.empty());
  EXPECT_EQ(vec.size(), 0u);

  ASSERT_TRUE(vec.Push(42));
  ASSERT_TRUE(!vec.empty());
  EXPECT_EQ(vec.size(), 1u);
  EXPECT_EQ(vec[0], 42u);
}

TEST(VectorTest, MoveConstructor) {
  Vector<size_t> vec;
  for (size_t i = 0; i < 100; i++) {
    ASSERT_TRUE(vec.Push(i));
  }

  Vector<size_t> vec_moved(std::move(vec));
  for (size_t i = 0; i < 100; i++) {
    EXPECT_EQ(vec_moved[i], i);
  }
}

TEST(VectorTest, VectorContainingVectors) {
  // Representative example of a struct that contains a Vector.
  struct TagAndArray {
    size_t tag;
    Vector<size_t> vec;
  };

  Vector<TagAndArray> vec;
  for (size_t i = 0; i < 100; i++) {
    TagAndArray elem;
    elem.tag = i;
    for (size_t j = 0; j < i; j++) {
      ASSERT_TRUE(elem.vec.Push(j));
    }
    ASSERT_TRUE(vec.Push(std::move(elem)));
  }
  EXPECT_EQ(vec.size(), static_cast<size_t>(100));

  Vector<TagAndArray> vec_moved(std::move(vec));
  EXPECT_EQ(vec_moved.size(), static_cast<size_t>(100));
  size_t count = 0;
  for (const TagAndArray &elem : vec_moved) {
    // Test the square bracket operator returns the same value as iteration.
    EXPECT_EQ(&elem, &vec_moved[count]);

    EXPECT_EQ(elem.tag, count);
    EXPECT_EQ(elem.vec.size(), count);
    for (size_t j = 0; j < count; j++) {
      EXPECT_EQ(elem.vec[j], j);
    }
    count++;
  }
}

TEST(VectorTest, NotDefaultConstructible) {
  struct NotDefaultConstructible {
    explicit NotDefaultConstructible(size_t n) { array.Init(n); }
    Array<int> array;
  };

  Vector<NotDefaultConstructible> vec;
  vec.Push(NotDefaultConstructible(0));
  vec.Push(NotDefaultConstructible(1));
  vec.Push(NotDefaultConstructible(2));
  vec.Push(NotDefaultConstructible(3));
  EXPECT_EQ(vec.size(), 4u);
  EXPECT_EQ(0u, vec[0].array.size());
  EXPECT_EQ(1u, vec[1].array.size());
  EXPECT_EQ(2u, vec[2].array.size());
  EXPECT_EQ(3u, vec[3].array.size());
}

TEST(VectorDeathTest, BoundsChecks) {
  Vector<int> vec;
  ASSERT_TRUE(vec.Push(1));
  // Within bounds of the capacity, but not the vector.
  EXPECT_DEATH_IF_SUPPORTED(vec[1], "");
  // Not within bounds of the capacity either.
  EXPECT_DEATH_IF_SUPPORTED(vec[10000], "");
}

TEST(InplaceVector, Basic) {
  InplaceVector<int, 4> vec;
  EXPECT_TRUE(vec.empty());
  EXPECT_EQ(0u, vec.size());
  EXPECT_EQ(vec.begin(), vec.end());

  int data3[] = {1, 2, 3};
  ASSERT_TRUE(vec.TryCopyFrom(data3));
  EXPECT_FALSE(vec.empty());
  EXPECT_EQ(3u, vec.size());
  auto iter = vec.begin();
  EXPECT_EQ(1, vec[0]);
  EXPECT_EQ(1, *iter);
  iter++;
  EXPECT_EQ(2, vec[1]);
  EXPECT_EQ(2, *iter);
  iter++;
  EXPECT_EQ(3, vec[2]);
  EXPECT_EQ(3, *iter);
  iter++;
  EXPECT_EQ(iter, vec.end());
  EXPECT_EQ(MakeConstSpan(vec), MakeConstSpan(data3));

  InplaceVector<int, 4> vec2 = vec;
  EXPECT_EQ(MakeConstSpan(vec), MakeConstSpan(vec2));

  InplaceVector<int, 4> vec3;
  vec3 = vec;
  EXPECT_EQ(MakeConstSpan(vec), MakeConstSpan(vec2));

  int data4[] = {1, 2, 3, 4};
  ASSERT_TRUE(vec.TryCopyFrom(data4));
  EXPECT_EQ(MakeConstSpan(vec), MakeConstSpan(data4));

  int data5[] = {1, 2, 3, 4, 5};
  EXPECT_FALSE(vec.TryCopyFrom(data5));
  EXPECT_FALSE(vec.TryResize(5));

  // Shrink the vector.
  ASSERT_TRUE(vec.TryResize(3));
  EXPECT_EQ(MakeConstSpan(vec), MakeConstSpan(data3));

  // Enlarge it again. The new value should have been value-initialized.
  ASSERT_TRUE(vec.TryResize(4));
  EXPECT_EQ(vec[3], 0);

  // Self-assignment should not break the vector. Indirect through a pointer to
  // avoid tripping a compiler warning.
  vec.CopyFrom(data4);
  const auto *ptr = &vec;
  vec = *ptr;
  EXPECT_EQ(MakeConstSpan(vec), MakeConstSpan(data4));
}

TEST(InplaceVectorTest, ComplexType) {
  InplaceVector<std::vector<int>, 4> vec_of_vecs;
  const std::vector<int> data[] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
  vec_of_vecs.CopyFrom(data);
  EXPECT_EQ(MakeConstSpan(vec_of_vecs), MakeConstSpan(data));

  vec_of_vecs.Resize(2);
  EXPECT_EQ(MakeConstSpan(vec_of_vecs), MakeConstSpan(data, 2));

  vec_of_vecs.Resize(4);
  EXPECT_EQ(4u, vec_of_vecs.size());
  EXPECT_EQ(vec_of_vecs[0], data[0]);
  EXPECT_EQ(vec_of_vecs[1], data[1]);
  EXPECT_TRUE(vec_of_vecs[2].empty());
  EXPECT_TRUE(vec_of_vecs[3].empty());

  // Copy-construction.
  InplaceVector<std::vector<int>, 4> vec_of_vecs2 = vec_of_vecs;
  EXPECT_EQ(4u, vec_of_vecs2.size());
  EXPECT_EQ(vec_of_vecs2[0], data[0]);
  EXPECT_EQ(vec_of_vecs2[1], data[1]);
  EXPECT_TRUE(vec_of_vecs2[2].empty());
  EXPECT_TRUE(vec_of_vecs2[3].empty());

  // Copy-assignment.
  InplaceVector<std::vector<int>, 4> vec_of_vecs3;
  vec_of_vecs3 = vec_of_vecs;
  EXPECT_EQ(4u, vec_of_vecs3.size());
  EXPECT_EQ(vec_of_vecs3[0], data[0]);
  EXPECT_EQ(vec_of_vecs3[1], data[1]);
  EXPECT_TRUE(vec_of_vecs3[2].empty());
  EXPECT_TRUE(vec_of_vecs3[3].empty());

  // Move-construction.
  InplaceVector<std::vector<int>, 4> vec_of_vecs4 = std::move(vec_of_vecs);
  EXPECT_EQ(4u, vec_of_vecs4.size());
  EXPECT_EQ(vec_of_vecs4[0], data[0]);
  EXPECT_EQ(vec_of_vecs4[1], data[1]);
  EXPECT_TRUE(vec_of_vecs4[2].empty());
  EXPECT_TRUE(vec_of_vecs4[3].empty());

  // The elements of the original vector should have been moved-from.
  EXPECT_EQ(4u, vec_of_vecs.size());
  for (const auto &vec : vec_of_vecs) {
    EXPECT_TRUE(vec.empty());
  }

  // Move-assignment.
  InplaceVector<std::vector<int>, 4> vec_of_vecs5;
  vec_of_vecs5 = std::move(vec_of_vecs4);
  EXPECT_EQ(4u, vec_of_vecs5.size());
  EXPECT_EQ(vec_of_vecs5[0], data[0]);
  EXPECT_EQ(vec_of_vecs5[1], data[1]);
  EXPECT_TRUE(vec_of_vecs5[2].empty());
  EXPECT_TRUE(vec_of_vecs5[3].empty());

  // The elements of the original vector should have been moved-from.
  EXPECT_EQ(4u, vec_of_vecs4.size());
  for (const auto &vec : vec_of_vecs4) {
    EXPECT_TRUE(vec.empty());
  }

  std::vector<int> v = {42};
  vec_of_vecs5.Resize(3);
  EXPECT_TRUE(vec_of_vecs5.TryPushBack(v));
  EXPECT_EQ(v, vec_of_vecs5[3]);
  EXPECT_FALSE(vec_of_vecs5.TryPushBack(v));
}

TEST(InplaceVectorTest, EraseIf) {
  // Test that EraseIf never causes a self-move, and also correctly works with
  // a move-only type that cannot be default-constructed.
  class NoSelfMove {
   public:
    explicit NoSelfMove(int v) : v_(std::make_unique<int>(v)) {}
    NoSelfMove(NoSelfMove &&other) { *this = std::move(other); }
    NoSelfMove &operator=(NoSelfMove &&other) {
      BSSL_CHECK(this != &other);
      v_ = std::move(other.v_);
      return *this;
    }

    int value() const { return *v_; }

   private:
    std::unique_ptr<int> v_;
  };

  InplaceVector<NoSelfMove, 8> vec;
  auto reset = [&] {
    vec.clear();
    for (int i = 0; i < 8; i++) {
      vec.PushBack(NoSelfMove(i));
    }
  };
  auto expect = [&](const std::vector<int> &expected) {
    ASSERT_EQ(vec.size(), expected.size());
    for (size_t i = 0; i < vec.size(); i++) {
      SCOPED_TRACE(i);
      EXPECT_EQ(vec[i].value(), expected[i]);
    }
  };

  reset();
  vec.EraseIf([](const auto &) { return false; });
  expect({0, 1, 2, 3, 4, 5, 6, 7});

  reset();
  vec.EraseIf([](const auto &) { return true; });
  expect({});

  reset();
  vec.EraseIf([](const auto &v) { return v.value() < 4; });
  expect({4, 5, 6, 7});

  reset();
  vec.EraseIf([](const auto &v) { return v.value() >= 4; });
  expect({0, 1, 2, 3});

  reset();
  vec.EraseIf([](const auto &v) { return v.value() % 2 == 0; });
  expect({1, 3, 5, 7});

  reset();
  vec.EraseIf([](const auto &v) { return v.value() % 2 == 1; });
  expect({0, 2, 4, 6});

  reset();
  vec.EraseIf([](const auto &v) { return 2 <= v.value() && v.value() <= 5; });
  expect({0, 1, 6, 7});

  reset();
  vec.EraseIf([](const auto &v) { return v.value() == 0; });
  expect({1, 2, 3, 4, 5, 6, 7});

  reset();
  vec.EraseIf([](const auto &v) { return v.value() == 4; });
  expect({0, 1, 2, 3, 5, 6, 7});

  reset();
  vec.EraseIf([](const auto &v) { return v.value() == 7; });
  expect({0, 1, 2, 3, 4, 5, 6});
}

TEST(InplaceVectorDeathTest, BoundsChecks) {
  InplaceVector<int, 4> vec;
  // The vector is currently empty.
  EXPECT_DEATH_IF_SUPPORTED(vec[0], "");
  int data[] = {1, 2, 3};
  vec.CopyFrom(data);
  // Some more out-of-bounds elements.
  EXPECT_DEATH_IF_SUPPORTED(vec[3], "");
  EXPECT_DEATH_IF_SUPPORTED(vec[4], "");
  EXPECT_DEATH_IF_SUPPORTED(vec[1000], "");
  // The vector cannot be resized past the capacity.
  EXPECT_DEATH_IF_SUPPORTED(vec.Resize(5), "");
  EXPECT_DEATH_IF_SUPPORTED(vec.ResizeForOverwrite(5), "");
  int too_much_data[] = {1, 2, 3, 4, 5};
  EXPECT_DEATH_IF_SUPPORTED(vec.CopyFrom(too_much_data), "");
  vec.Resize(4);
  EXPECT_DEATH_IF_SUPPORTED(vec.PushBack(42), "");
}

TEST(ReconstructSeqnumTest, Increment) {
  // Test simple cases from the beginning of an epoch with both 8- and 16-bit
  // wire sequence numbers.
  EXPECT_EQ(reconstruct_seqnum(0, 0xff, 0), 0u);
  EXPECT_EQ(reconstruct_seqnum(1, 0xff, 0), 1u);
  EXPECT_EQ(reconstruct_seqnum(2, 0xff, 0), 2u);
  EXPECT_EQ(reconstruct_seqnum(0, 0xffff, 0), 0u);
  EXPECT_EQ(reconstruct_seqnum(1, 0xffff, 0), 1u);
  EXPECT_EQ(reconstruct_seqnum(2, 0xffff, 0), 2u);

  // When the max seen sequence number is 0, the numerically closest
  // reconstructed sequence number could be negative. Sequence numbers are
  // non-negative, so reconstruct_seqnum should instead return the closest
  // non-negative number instead of returning a number congruent to that
  // closest negative number mod 2^64.
  EXPECT_EQ(reconstruct_seqnum(0xff, 0xff, 0), 0xffu);
  EXPECT_EQ(reconstruct_seqnum(0xfe, 0xff, 0), 0xfeu);
  EXPECT_EQ(reconstruct_seqnum(0xffff, 0xffff, 0), 0xffffu);
  EXPECT_EQ(reconstruct_seqnum(0xfffe, 0xffff, 0), 0xfffeu);

  // When the wire sequence number is less than the corresponding low bytes of
  // the max seen sequence number, check that the next larger sequence number
  // is reconstructed as its numerically closer than the corresponding sequence
  // number that would keep the high order bits the same.
  EXPECT_EQ(reconstruct_seqnum(0, 0xff, 0xff), 0x100u);
  EXPECT_EQ(reconstruct_seqnum(1, 0xff, 0xff), 0x101u);
  EXPECT_EQ(reconstruct_seqnum(2, 0xff, 0xff), 0x102u);
  EXPECT_EQ(reconstruct_seqnum(0, 0xffff, 0xffff), 0x10000u);
  EXPECT_EQ(reconstruct_seqnum(1, 0xffff, 0xffff), 0x10001u);
  EXPECT_EQ(reconstruct_seqnum(2, 0xffff, 0xffff), 0x10002u);

  // Test cases when the wire sequence number is close to the largest magnitude
  // that can be represented in 8 or 16 bits.
  EXPECT_EQ(reconstruct_seqnum(0xff, 0xff, 0x2f0), 0x2ffu);
  EXPECT_EQ(reconstruct_seqnum(0xfe, 0xff, 0x2f0), 0x2feu);
  EXPECT_EQ(reconstruct_seqnum(0xffff, 0xffff, 0x2f000), 0x2ffffu);
  EXPECT_EQ(reconstruct_seqnum(0xfffe, 0xffff, 0x2f000), 0x2fffeu);

  // Test that reconstruct_seqnum can return the maximum sequence number,
  // 2^48-1.
  constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1;
  EXPECT_EQ(reconstruct_seqnum(0xff, 0xff, kMaxSequence), kMaxSequence);
  EXPECT_EQ(reconstruct_seqnum(0xff, 0xff, kMaxSequence - 1), kMaxSequence);
  EXPECT_EQ(reconstruct_seqnum(0xffff, 0xffff, kMaxSequence), kMaxSequence);
  EXPECT_EQ(reconstruct_seqnum(0xffff, 0xffff, kMaxSequence - 1), kMaxSequence);
}

TEST(ReconstructSeqnumTest, Decrement) {
  // Test that the sequence number 0 can be reconstructed when the max
  // seen sequence number is greater than 0.
  EXPECT_EQ(reconstruct_seqnum(0, 0xff, 0x10), 0u);
  EXPECT_EQ(reconstruct_seqnum(0, 0xffff, 0x1000), 0u);

  // Test cases where the reconstructed sequence number is less than the max
  // seen sequence number.
  EXPECT_EQ(reconstruct_seqnum(0, 0xff, 0x210), 0x200u);
  EXPECT_EQ(reconstruct_seqnum(2, 0xff, 0x210), 0x202u);
  EXPECT_EQ(reconstruct_seqnum(0, 0xffff, 0x43210), 0x40000u);
  EXPECT_EQ(reconstruct_seqnum(2, 0xffff, 0x43210), 0x40002u);

  // Test when the wire sequence number is greater than the low bits of the
  // max seen sequence number.
  EXPECT_EQ(reconstruct_seqnum(0xff, 0xff, 0x200), 0x1ffu);
  EXPECT_EQ(reconstruct_seqnum(0xfe, 0xff, 0x200), 0x1feu);
  EXPECT_EQ(reconstruct_seqnum(0xffff, 0xffff, 0x20000), 0x1ffffu);
  EXPECT_EQ(reconstruct_seqnum(0xfffe, 0xffff, 0x20000), 0x1fffeu);

  constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1;
  // kMaxSequence00 is kMaxSequence with the last byte replaced with 0x00.
  constexpr uint64_t kMaxSequence00 = kMaxSequence - 0xff;
  // kMaxSequence0000 is kMaxSequence with the last byte replaced with 0x0000.
  constexpr uint64_t kMaxSequence0000 = kMaxSequence - 0xffff;

  // Test when the max seen sequence number is close to the 2^48-1 max value.
  // In some cases, the closest numerical value in the integers will exceed the
  // limit. In this case, reconstruct_seqnum should return the closest integer
  // within range.
  EXPECT_EQ(reconstruct_seqnum(0, 0xff, kMaxSequence), kMaxSequence00);
  EXPECT_EQ(reconstruct_seqnum(0, 0xff, kMaxSequence - 1), kMaxSequence00);
  EXPECT_EQ(reconstruct_seqnum(1, 0xff, kMaxSequence), kMaxSequence00 + 0x01);
  EXPECT_EQ(reconstruct_seqnum(1, 0xff, kMaxSequence - 1),
            kMaxSequence00 + 0x01);
  EXPECT_EQ(reconstruct_seqnum(0xfe, 0xff, kMaxSequence),
            kMaxSequence00 + 0xfe);
  EXPECT_EQ(reconstruct_seqnum(0xfd, 0xff, kMaxSequence - 1),
            kMaxSequence00 + 0xfd);
  EXPECT_EQ(reconstruct_seqnum(0, 0xffff, kMaxSequence), kMaxSequence0000);
  EXPECT_EQ(reconstruct_seqnum(0, 0xffff, kMaxSequence - 1), kMaxSequence0000);
  EXPECT_EQ(reconstruct_seqnum(1, 0xffff, kMaxSequence),
            kMaxSequence0000 + 0x0001);
  EXPECT_EQ(reconstruct_seqnum(1, 0xffff, kMaxSequence - 1),
            kMaxSequence0000 + 0x0001);
  EXPECT_EQ(reconstruct_seqnum(0xfffe, 0xffff, kMaxSequence),
            kMaxSequence0000 + 0xfffe);
  EXPECT_EQ(reconstruct_seqnum(0xfffd, 0xffff, kMaxSequence - 1),
            kMaxSequence0000 + 0xfffd);
}

TEST(ReconstructSeqnumTest, Halfway) {
  // Test wire sequence numbers that are close to halfway away from the max
  // seen sequence number. The algorithm specifies that the output should be
  // numerically closest to 1 plus the max seen (0x100 in the following test
  // cases). With a max seen of 0x100 and a wire sequence of 0x81, the two
  // closest values to 1+0x100 are 0x81 and 0x181, which are both the same
  // amount away. The algorithm doesn't specify what to do on this edge case;
  // our implementation chooses the larger value (0x181), on the assumption that
  // it's more likely to be a new or larger sequence number rather than a replay
  // or an out-of-order packet.
  EXPECT_EQ(reconstruct_seqnum(0x80, 0xff, 0x100), 0x180u);
  EXPECT_EQ(reconstruct_seqnum(0x81, 0xff, 0x100), 0x181u);
  EXPECT_EQ(reconstruct_seqnum(0x82, 0xff, 0x100), 0x82u);

  // Repeat these tests with 16-bit wire sequence numbers.
  EXPECT_EQ(reconstruct_seqnum(0x8000, 0xffff, 0x10000), 0x18000u);
  EXPECT_EQ(reconstruct_seqnum(0x8001, 0xffff, 0x10000), 0x18001u);
  EXPECT_EQ(reconstruct_seqnum(0x8002, 0xffff, 0x10000), 0x8002u);
}

TEST(DTLSMessageBitmapTest, Basic) {
  // expect_bitmap checks that |b|'s unmarked bits are those listed in |ranges|.
  // Each element of |ranges| must be non-empty and non-overlapping, and
  // |ranges| must be sorted.
  auto expect_bitmap = [](const DTLSMessageBitmap &b,
                          const std::vector<DTLSMessageBitmap::Range> &ranges) {
    EXPECT_EQ(ranges.empty(), b.IsComplete());
    size_t start = 0;
    for (const auto &r : ranges) {
      for (; start < r.start; start++) {
        SCOPED_TRACE(start);
        EXPECT_EQ(b.NextUnmarkedRange(start), r);
      }
      for (; start < r.end; start++) {
        SCOPED_TRACE(start);
        EXPECT_EQ(b.NextUnmarkedRange(start),
                  (DTLSMessageBitmap::Range{start, r.end}));
      }
    }
    EXPECT_TRUE(b.NextUnmarkedRange(start).empty());
    EXPECT_TRUE(b.NextUnmarkedRange(start + 1).empty());
    EXPECT_TRUE(b.NextUnmarkedRange(start + 42).empty());

    // This is implied from the previous checks, but NextUnmarkedRange should
    // work as an iterator to reconstruct the ranges.
    std::vector<DTLSMessageBitmap::Range> got_ranges;
    for (auto r = b.NextUnmarkedRange(0); !r.empty();
         r = b.NextUnmarkedRange(r.end)) {
      got_ranges.push_back(r);
    }
    EXPECT_EQ(ranges, got_ranges);
  };

  // Initially, the bitmap is empty (fully marked).
  DTLSMessageBitmap bitmap;
  expect_bitmap(bitmap, {});

  // It can also be initialized to the empty message and marked.
  ASSERT_TRUE(bitmap.Init(0));
  expect_bitmap(bitmap, {});
  bitmap.MarkRange(0, 0);
  expect_bitmap(bitmap, {});

  // Track 100 bits and mark byte by byte.
  ASSERT_TRUE(bitmap.Init(100));
  expect_bitmap(bitmap, {{0, 100}});
  for (size_t i = 0; i < 100; i++) {
    SCOPED_TRACE(i);
    bitmap.MarkRange(i, i + 1);
    if (i < 99) {
      expect_bitmap(bitmap, {{i + 1, 100}});
    } else {
      expect_bitmap(bitmap, {});
    }
  }

  // Do the same but in reverse.
  ASSERT_TRUE(bitmap.Init(100));
  expect_bitmap(bitmap, {{0, 100}});
  for (size_t i = 100; i > 0; i--) {
    SCOPED_TRACE(i);
    bitmap.MarkRange(i - 1, i);
    if (i > 1) {
      expect_bitmap(bitmap, {{0, i - 1}});
    } else {
      expect_bitmap(bitmap, {});
    }
  }

  // Overlapping ranges are fine.
  ASSERT_TRUE(bitmap.Init(100));
  expect_bitmap(bitmap, {{0, 100}});
  for (size_t i = 0; i < 100; i++) {
    SCOPED_TRACE(i);
    bitmap.MarkRange(i / 2, i + 1);
    if (i < 99) {
      expect_bitmap(bitmap, {{i + 1, 100}});
    } else {
      expect_bitmap(bitmap, {});
    }
  }

  // Mark the middle chunk of every power of 3.
  ASSERT_TRUE(bitmap.Init(100));
  bitmap.MarkRange(1, 2);
  bitmap.MarkRange(3, 6);
  bitmap.MarkRange(9, 18);
  bitmap.MarkRange(27, 54);
  bitmap.MarkRange(81, 162);
  expect_bitmap(bitmap, {{0, 1}, {2, 3}, {6, 9}, {18, 27}, {54, 81}});

  // Mark most of the chunk shifted down a bit, so it both overlaps the previous
  // and also leaves some of the right chunks unmarked.
  bitmap.MarkRange(6 - 2, 9 - 2);
  bitmap.MarkRange(18 - 4, 27 - 4);
  bitmap.MarkRange(54 - 8, 81 - 8);
  expect_bitmap(bitmap,
                {{0, 1}, {2, 3}, {9 - 2, 9}, {27 - 4, 27}, {81 - 8, 81}});

  // Re-mark things that have already been marked.
  bitmap.MarkRange(1, 2);
  bitmap.MarkRange(3, 6);
  bitmap.MarkRange(9, 18);
  bitmap.MarkRange(27, 54);
  bitmap.MarkRange(81, 162);
  expect_bitmap(bitmap,
                {{0, 1}, {2, 3}, {9 - 2, 9}, {27 - 4, 27}, {81 - 8, 81}});

  // Moves should work.
  DTLSMessageBitmap bitmap2 = std::move(bitmap);
  expect_bitmap(bitmap, {});
  expect_bitmap(bitmap2,
                {{0, 1}, {2, 3}, {9 - 2, 9}, {27 - 4, 27}, {81 - 8, 81}});

  // Mark everything in two large ranges.
  bitmap2.MarkRange(27 - 2, 100);
  expect_bitmap(bitmap2, {{0, 1}, {2, 3}, {9 - 2, 9}, {27 - 4, 27 - 2}});
  bitmap2.MarkRange(0, 50);
  expect_bitmap(bitmap2, {});
}

}  // namespace
BSSL_NAMESPACE_END
#endif  // !BORINGSSL_SHARED_LIBRARY
