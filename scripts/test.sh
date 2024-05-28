python -m \
  coverage run -m pytest \
    --html ./src/app/static/test-results.html \
    --count 3 \
    -n 4 \
    $@

coverage html
