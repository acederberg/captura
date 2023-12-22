
cd /app
source venv/bin/activate

EXISTS=$( pip list | grep documents-server )
if [[ ! $EXISTS ]]; then python -m pip install --editable .; fi
