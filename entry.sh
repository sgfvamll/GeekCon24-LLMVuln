
cd /app/forpentest
nohup python3 ./web.py > /app/forpentest/nohup.out 2>&1 &

cd /app/forpwn
nohup python3 ./web.py > /app/forpwn/nohup.out 2>&1 &

sleep infinity & wait
