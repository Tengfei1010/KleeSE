//===-- Timer.cpp ---------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/Support/Timer.h"

#include "klee/Internal/System/Time.h"

using namespace klee;
using namespace llvm;

WallTimer::WallTimer() {
  start = util::getWallTimeVal();
}

uint64_t WallTimer::check() {
  sys::TimePoint<> now = util::getWallTimeVal();
  return std::chrono::duration_cast<std::chrono::microseconds>(now -
    start).count();
}

