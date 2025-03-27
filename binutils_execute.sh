#!/bin/bash

# Vérifier si un argument a été fourni
if [ -z "$1" ]; then
  echo "Usage: $0 <option>"
  exit 1
fi

# Utiliser le premier argument comme option pour la commande
OPTION="$1"

cmake --build build
# Répertoire contenant les fichiers binaires ELF
BINARY_DIR="../binutils-gdb/binutils-install/bin/"
# Répertoire pour enregistrer les résultats
RESULTS_DIR="results/binutils"
# Commande à exécuter
COMMAND="./build/desassam"

# Créer le répertoire de résultats s'il n'existe pas
mkdir -p "$RESULTS_DIR"

# Initialiser ou vider le fichier OverallResults.txt
> "$RESULTS_DIR/OverallResults.txt"

# Parcourir tous les fichiers dans le répertoire des binaires
for file in "$BINARY_DIR"/*; do
  # Extraire le nom du fichier sans l'extension
  filename=$(basename "$file")
  # Exécuter la commande avec l'option fournie et rediriger la sortie vers le fichier de résultats
  $COMMAND "$file" ON "$OPTION" > "$RESULTS_DIR/${filename}.txt"

  # Ajouter le nom du fichier et la dernière ligne du fichier de résultats à OverallResults.txt
  echo "Results for $filename:" >> "$RESULTS_DIR/OverallResults.txt"
  tail -n 1 "$RESULTS_DIR/${filename}.txt" >> "$RESULTS_DIR/OverallResults.txt"
  echo "" >> "$RESULTS_DIR/OverallResults.txt"  # Ajouter une ligne vide pour la lisibilité
done
