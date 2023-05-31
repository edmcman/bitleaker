# This is a Dockerfile that allows us to use the relatively newish tpm2_eventlog parser
FROM ubuntu:22.04

RUN apt update && apt install tpm2-tools -y

CMD ["tpm2_eventlog"]