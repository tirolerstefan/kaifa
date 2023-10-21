FROM python:slim

WORKDIR /app
RUN mkdir /etc/kaifareader
ADD kaifareader.py /app/
ADD meter_template.json /etc/kaifareader/meter_template.json
ADD meter_template.json /etc/kaifareader/meter.json

RUN pip install pycryptodomex paho-mqtt influxdb-client pyserial
ENV TZ=Europe/Vienna
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

CMD [ "python", "./kaifareader.py" ]
