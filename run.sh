nohup python3 -u /home/hejun/project/skillscan/scan_and_analyze.py \
  --watch-root /home/hejun/project/clawhub \
  --watch-date today \
  --dir /home/hejun/project/clawhub \
  --output /home/hejun/project/skillscan \
  --log /home/hejun/project/skillscan/logs \
  --use-llm -p isrc \
  --model GLM-4.5 \
  --watch-interval-seconds 60 \
  --watch-min-age-seconds 120 \
  > /home/hejun/project/skillscan/logs/watch_runner3.log 2>&1 &