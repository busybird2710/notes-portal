# Dockerfile

# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install the system dependencies for PyAudio and other libraries
# `portaudio19-dev` is for PyAudio
# `libasound-dev` and `python3-xlib` are often required for mouse/keyboard automation libraries
RUN apt-get update && apt-get install -y \
    portaudio19-dev \
    libasound-dev \
    python3-xlib \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define environment variable
ENV NAME="My-Flask-App"

# Run gunicorn when the container launches
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]