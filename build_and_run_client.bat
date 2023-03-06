docker-compose build vpn_client
docker-compose kill vpn_client
docker-compose up -d vpn_client
docker-compose logs vpn_client -f