# NOTE: This will be mounted as the bashrc for the default user.
cd /app
source venv/bin/activate

EXISTS=$( pip list | grep documents-server )
if [[ ! $EXISTS ]]; then python -m pip install --editable .; fi

EXISTS=$( pip list | grep pytest )
if [[ ! $EXISTS ]]; then python -m pip install .[test]; fi

export PATH="$PATH:$(realpath ~/.local/bin)"
