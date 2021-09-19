/// Asserts that `it` adheres to the `ExactSizeIterator` contract.
pub fn assert_exact_size_iterator<T>(mut it: impl ExactSizeIterator<Item = T>, expected: &[T])
where
    T: Copy + core::fmt::Debug + PartialEq,
{
    assert_eq!(it.len(), expected.len());
    assert_eq!(it.size_hint(), expected.iter().size_hint());

    for i in 0..expected.len() {
        let len = it.len();
        assert_eq!(len, expected.len() - i);
        assert_eq!(it.size_hint(), (len, Some(len)));
        assert_eq!(it.next(), Some(expected[i]));
    }

    assert_eq!(it.len(), 0);
    assert_eq!(it.size_hint(), (0, Some(0)));
    assert_eq!(it.next(), None);
}
