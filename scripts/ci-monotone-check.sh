#!/bin/bash

echo "Running monotone capability tests..."

cargo test

if [ $? -ne 0 ]; then
  echo "Capability monotonicity violated."
  exit 1
fi

echo "Aegis Shield invariant OK."
