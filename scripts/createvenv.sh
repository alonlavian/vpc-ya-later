# This will create the virtual environment
echo "Creating Virtual Environemnt"
python3 -m venv ~/projects/VSCode/BlastMotion/sgupdates/v-env

echo "Activating Virtual Enviornment"
source ~/projects/VSCode/BlastMotion/sgupdates/v-env/bin/activate

echo "Upgrading pip"
~/projects/VSCode/BlastMotion/sgupdates/v-env/bin/pip3 install --upgrade pip

echo "Installing Requirements"
~/projects/VSCode/BlastMotion/sgupdates/v-env/bin/pip3 install -r requirements.txt
