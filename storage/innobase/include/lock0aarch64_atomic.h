#ifndef lock0aarch64_atomic_h
#define lock0aarch64_atomic_h

#include "univ.i"

lint word_add_fetch(volatile lint *word, ulint amount);

#endif /* lock0aarch64_atomic_h */