python -m \
  coverage run -m pytest \
    --html ./src/app/static/test-results.html \
    --durations 25 \
    $@

coverage html
