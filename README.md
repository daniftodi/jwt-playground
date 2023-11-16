# Getting Started

This is a simple application that generates a JWT token using the ECDSA algorithm
then it is posted to an endpoint using the default Java Http client. 

### Generating keys


> openssl ecparam -name secp384r1 -genkey -noout -out private.pem

> openssl ec -in private.pem -pubout -out public.pem
