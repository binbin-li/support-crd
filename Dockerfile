# Use the Alpine base image
FROM alpine@sha256:2c43f33bd1502ec7818bce9eea60e062d04eeadc4aa31cad9dabecb1e48b647b

# Set the working directory inside the container
WORKDIR /app

# Add the hello world script
RUN echo "echo Hello, World!" > hello.sh

# Make the script executable
RUN chmod +x hello.sh

# Set the default command to run the script
CMD ["./hello.sh"]k