docker-compose build vpn_server
docker-compose kill vpn_server
docker-compose up -d vpn_server
docker-compose logs vpn_server -f