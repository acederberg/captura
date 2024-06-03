# NOTE: This will be mounted as the bashrc for the default user.

# Go to WORKDIR
cd /app


# Virtual environment
if [[ ! -d .venv ]]; then
  echo "Virtual environment does not exist. Creating under \`.venv\`."
  python -m venv .venv
else
  echo "Virtual environment already exists.";
fi

source .venv/bin/activate


# Install app and test dependencies.
EXISTS=$( pip list 2> /dev/null | grep articles-api )
if [[ ! $EXISTS ]]; then
  echo "Python project not installed in virtual environment. Installing."
  python -m pip install --editable .
else
  echo "Python project already installed in virtual environment."
fi


EXISTS=$( pip list 2> /dev/null | grep pytest )
if [[ ! $EXISTS ]]; then
  echo "Python project test dependencies not installed. Installing."
  python -m pip install .[test];
else
  echo "Python project test dependencies already installed."
fi

export PATH="$PATH:$(realpath ~/.local/bin)"

export CAPTURA_SESSION_SECRET=$( python -c "import secrets; print(secrets.token_urlsafe())" )
