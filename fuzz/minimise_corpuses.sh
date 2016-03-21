set -e

buildDir=../build
if [ $# -gt 0 ]; then
  buildDir=$1
fi

for testSource in $(ls -1 *.cc); do
  test=$(echo $testSource | sed -e 's/\.cc$//')
  if [ ! -x $buildDir/fuzz/$test ] ; then
    echo "Failed to find binary for $test"
    exit 1
  fi
  if [ ! -d ${test}_corpus ]; then
    echo "Failed to find corpus directory for $test"
    exit 1
  fi
  if [ -d ${test}_corpus_old ]; then
    echo "Old corpus directory for $test already exists"
    exit 1
  fi
done

for testSource in $(ls -1 *.cc); do
  test=$(echo $testSource | sed -e 's/\.cc$//')
  mv ${test}_corpus ${test}_corpus_old
  mkdir ${test}_corpus
  $buildDir/fuzz/$test -max_len=50000 -merge=1 ${test}_corpus ${test}_corpus_old
  rm -Rf ${test}_corpus_old
done
