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
