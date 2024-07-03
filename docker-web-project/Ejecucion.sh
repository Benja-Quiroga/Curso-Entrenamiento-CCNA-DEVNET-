#!/bin/bash

# Crear un directorio temporal
TEMP_DIR=$(mktemp -d)

# Copiar los archivos del sitio web al directorio temporal
mkdir -p $TEMP_DIR/web
cp -r web/* $TEMP_DIR/web

# Crear el Dockerfile en el directorio temporal
cat <<EOF > $TEMP_DIR/Dockerfile
# Usar la imagen base de Python
FROM python:3.8-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar los archivos del sitio web al contenedor
COPY web/ /app/web/

# Instalar las dependencias
RUN pip install flask

# Exponer el puerto
EXPOSE 7075

# Comando para ejecutar la aplicación
CMD ["python", "/app/web/dapp2.py"]
EOF

# Construir el contenedor Docker
docker build -t my-web-app $TEMP_DIR

# Detener y eliminar cualquier contenedor anterior con el mismo nombre
docker stop web-app 2>/dev/null || true
docker rm web-app 2>/dev/null || true

# Iniciar el contenedor Docker
docker run -d -p 7075:7075 --name web-app my-web-app

# Comprobar que el contenedor está en ejecución
docker ps

# Añadir un retraso para que el contenedor inicie completamente
echo "Esperando 10 segundos para que el contenedor se inicie completamente..."
sleep 10

# Comprobar la ejecución de la página web de muestra con curl
curl http://localhost:7075

# Limpiar el directorio temporal
rm -rf $TEMP_DIR
