#include "lock0aarch64_atomic.h"

lint word_add_fetch(volatile lint *word, ulint amount) {
  asm volatile (
    "ldaddal %0, x3, [%1]\n\t"
    "add %0, x3, %0"
      :"+r"(amount)
      :"r"(word)
      :"x3","memory"
  );
  return amount;
}