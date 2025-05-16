#!/bin/bash

# Vérifier si les arguments nécessaires sont fournis
if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <1_strip=ON|OFF> <2_optionMOV=ON|OFF> <3_optionPADD=ON|OFF>  <4_optionHelpFuzzing<ON|OFF>"
  exit 1
fi

# Handle strip option
if [ "$1" = "ON" ]; then
  # Répertoire contenant les fichiers binaires ELF
  BINARY_DIR="../binutils-gdb/binutils-install/bin_strip/"
elif [ "$1" = "OFF" ]; then
  # Répertoire contenant les fichiers binaires ELF
  BINARY_DIR="../binutils-gdb/binutils-install/bin/"
else
  echo "Error: Argument OptionMOV must be ON or OFF."
  exit 1
fi


# Vérifier si les arguments sont soit "ON" soit "OFF"
if [ "$2" != "ON" ] && [ "$2" != "OFF" ]; then
  echo "Error: Argument OptionMOV must be ON or OFF."
  exit 1
fi

if [ "$3" != "ON" ] && [ "$3" != "OFF" ]; then
  echo "Error: Argument OptionPADD must be ON or OFF."
  exit 1
fi

if [ "$4" != "ON" ] && [ "$4" != "OFF" ]; then
  echo "Error: Argument OptionHelpFuzz must be ON or OFF."
  exit 1
fi

# Si les arguments sont valides, continuer avec le reste du script
echo "strip is set to $1"
echo "OptionMOV is set to $2"
echo "OptionPADD is set to $3"
echo "optionHelpFuzzing is set to $4"

# Utiliser les arguments comme options pour la commande
strip=$1
OptionMOV="$2"
OptionPADD="$3"
optionHelpFuzzing="$4"

cmake --build build

# Répertoire pour enregistrer les résultats
RESULTS_DIR="results/binutils/strip.$strip/MOV.$OptionMOV/PADD.$OptionPADD/Fuzz.$optionHelpFuzzing"

# Créer le répertoire de résultats s'il n'existe pas
mkdir -p "$RESULTS_DIR"

# Commande à exécuter
COMMAND="./build/desassam"

# Chemin du fichier CSV de résultats
CSV_FILE="results/binutils/strip.$strip.MOV.$OptionMOV.PADD.$OptionPADD.Fuzz.$optionHelpFuzzing.Results.csv"

# Créer l'en-tête du fichier CSV
echo "Filename,strip,OptionMOV,OptionPADD,optionHelpFuzzing,code_address_recover(%),#bytes_in_code_segments_not_disass,#bytes_in_code_segments_total,#jmp_indirect" > "$CSV_FILE"

# Parcourir tous les fichiers dans le répertoire des binaires
for file in "$BINARY_DIR"/*; do
  # Extraire le nom du fichier sans l'extension
  filename=$(basename "$file")


  # Exécuter la commande et rediriger l'output dans un fichier
  $COMMAND "$file" "binutils" "$OptionMOV" "$OptionPADD" "$optionHelpFuzzing" > "$RESULTS_DIR/${filename}.txt"

  # Extraire la dernière ligne de l'output dans une variable
  results=$(tail -n 1 "$RESULTS_DIR/${filename}.txt")

  echo "$filename"

  # Extraire les valeurs des résultats
  result1=$(echo "$results" | awk '{print $1}')
  result2=$(echo "$results" | awk '{print $2}')
  result3=$(echo "$results" | awk '{print $3}')
  result4=$(echo "$results" | awk '{print $4}')

  # Ajouter les résultats au fichier CSV
  echo "$filename,$strip,$OptionMOV,$OptionPADD,$optionHelpFuzzing,$result1,$result2,$result3,$result4" >> "$CSV_FILE"
done
