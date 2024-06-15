# NOTE: This will be mounted as the bashrc for the default user.

export CAPTURA_HOME="/home/captura"
export PATH="$PATH:$CAPTURA_HOME/.local/bin"
export CAPTURA_WORKDIR="$CAPTURA_HOME/app" 
export CAPTURA_VENV="$CAPTURA_HOME/.venv" \
  CAPTURA_PLUGINS_CONFIG="$CAPTURA_HOME/plugins.yaml" \
  CAPTURA_PLUGINS_DIRECTORY="$CAPTURA_WORKDIR/plugins"  


function captura_venv (){
  if [[ $CAPTURA_APP__ENVIRONMENT = "production" ]]; then
    return
  fi

  # Virtual environment
  if [[ ! -d $CAPTURA_VENV ]]; then
    echo "Virtual environment does not exist. Creating under \`.venv\`."
    python -m venv $CAPTURA_VENV
  else
    echo "Virtual environment already exists.";
  fi

  source $CAPTURA_VENV/bin/activate
}


function captura_install_from_path(){

  # Install app and test dependencies.
  if [[ $CAPTURA_APP__ENVIRONMENT != "production" ]]; then
    echo "Installing dependencies for \`$1\` in editable mode."
    python -m pip install --editable $1
  else
    echo "Installing dependencies for \`$1\`."
    python -m pip install $1
  fi
}


function captura_install_plugins(){

  if $( test -d $CAPTURA_PLUGINS ); then
    echo "Found plugins in \`$CAPTURA_PLUGINS_DIRECTORY\`\!"
    plugins=$( ls -d $CAPTURA_PLUGINS_DIRECTORY/[a-zA-Z-]*/ | xargs -i realpath {} )
    for plugin in $plugins;
    do
      echo "Installing dependencies for \`$plugin\`."
      captura_install_from_path $plugins
    done
  else
    echo "No plugins found (in \`$CAPTURA_PLUGINS_DIRECTORY\`)."
  fi

}


# Install captura and any existing plugins.
function captura_install(){

  captura_install_from_path "$CAPTURA_WORKDIR" 
  captura_install_from_path "$CAPTURA_WORKDIR[test]" 
  captura_install_from_path "$CAPTURA_WORKDIR[plugins]" 

}

function captura_plugins() {
  if (test -d $CAPTURA_PLUGINS_DIRECTORY); then
    python -m plugins up
  fi

  captura_install_plugins "$CAPTURA_WORKDIR" 
}


function main(){
  cd $CAPTURA_WORKDIR

  if [[ "$1" = "install" ]]; then captura_install
  elif [[ "$1" = "plugins" ]]; then captura_plugins
  else echo "Doing nothing."; fi

  cd -
}


if [[ $CAPTURA_APP__ENVIRONMENT != "production" ]]; then captura_venv; fi
if [[ "$1" ]]; then main "$1"; fi


# export CAPTURA_SESSION_SECRET=$( python -c "import secrets; print(secrets.token_urlsafe())" )
