#!/usr/bin/env sh

GREEN='\033[0;32m'
NC='\033[0m' # No Color

if [ ! -d "symexec-bench" ]; then
    echo "Cloning symexec-bench..."
    git clone --depth 1 -b symtest --single-branch https://github.com/baolean/symexec-bench.git
else
    echo "Using existing symexec-bench checkout"
fi

for test_name in "PostExampleTest" "PostExampleTwoTest" "PostExampleTwoLiveTest" "FooTest" "MiniVatTest"; do
    echo
    echo -e "▀▄▀▄▀▄   🎀  Running ${GREEN}${test_name}${NC}  🎀   ▄▀▄▀▄▀"
    time dolmos --root symexec-bench/SymTest --contract ${test_name} "--function" test
done

