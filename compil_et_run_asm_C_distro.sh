#!/bin/bash

# Vérifier si les arguments nécessaires sont fournis
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <strip=ON|OFF> <OptionMOV=ON|OFF> <OptionPADD=ON|OFF>"
  exit 1
fi

# Handle strip option
if [ "$1" = "ON" ]; then
  # Répertoire contenant les fichiers binaires ELF
  BINARY_DIR="../binaries/elf_strip/"
elif [ "$1" = "OFF" ]; then
  # Répertoire contenant les fichiers binaires ELF
  BINARY_DIR="../binaries/elf/"
else
  echo "Error: Argument strip must be ON or OFF."
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

# Si les arguments sont valides, continuer avec le reste du script
echo "strip is set to $1"
echo "OptionMOV is set to $2"
echo "OptionPADD is set to $3"

# Utiliser les arguments comme options pour la commande
strip="$1"
OptionMOV="$2"
OptionPADD="$3"

cmake --build build

# Commande à exécuter
COMMAND="./build/desassam"

# Tableau des fichiers binaires à tester
declare -A binaries
binaries=(
  ["asm"]="jmp_imm jmp_reg data jmp_in_same_bb jmp_in_other_bb bar"
  ["C"]="return0 if_function hello_world_C function_pointer switch_lj switch_sj"
  ["Cpp"]="exception methode_virtuelle"
  ["Go"]="hello_world_Go"
  ["Rust"]="hello_world_rust"
)

# Exécuter les commandes pour tous les types de binaires
for BINARY_TYPE in "${!binaries[@]}"; do
  # Répertoire pour enregistrer les résultats
  RESULTS_DIR="results/$BINARY_TYPE/strip.$strip/MOV.$OptionMOV/PADD.$OptionPADD"
  # Fichier CSV de résultats pour chaque catégorie
  CSV_FILE="results/$BINARY_TYPE/strip.$strip.MOV.$OptionMOV.PADD.$OptionPADD.Results.csv"
  # Créer le répertoire de résultats s'il n'existe pas
  mkdir -p "$RESULTS_DIR"
  # Créer l'en-tête du fichier CSV
  echo "Filename,strip,OptionMOV,OptionPADD,code_address_recover(%),#bytes_in_code_segments_not_disass,#bytes_in_code_segments_total,#jmp_indirect" > "$CSV_FILE"
  
  for binary in ${binaries[$BINARY_TYPE]}; do
    # Construire le chemin du fichier binaire
    file_path="$BINARY_DIR/$binary"
    # Exécuter la commande et rediriger la sortie vers le fichier de résultats
    $COMMAND "$file_path" "$BINARY_TYPE" "$OptionMOV" "$OptionPADD" > "$RESULTS_DIR/$(basename "$binary").txt"

    # Extraire la dernière ligne de l'output dans une variable
    results=$(tail -n 1 "$RESULTS_DIR/$(basename "$binary").txt")

    # Extraire les valeurs des résultats
    result1=$(echo "$results" | awk '{print $1}')
    result2=$(echo "$results" | awk '{print $2}')
    result3=$(echo "$results" | awk '{print $3}')
    result4=$(echo "$results" | awk '{print $4}')

    # Ajouter les résultats au fichier CSV
    echo "$(basename "$binary"),$strip,$OptionMOV,$OptionPADD,$result1,$result2,$result3,$result4" >> "$CSV_FILE"
  done
done
