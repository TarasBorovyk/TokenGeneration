# TokenGeneration
1. Install latest docker desktop (if not installed)
2. Pull the solution
3. Inside project directory build image using the following command:  docker build -t tokengeneration .
4. Run project in docker using the following command:
   docker run -d -p 443:443 \
    -v /path/to/ssl/certificate:/app/ssl \
    -e ASPNETCORE_URLS=https://+:443;http://+:80 \
    -e ASPNETCORE_HTTPS_PORT=443 \
    -e ASPNETCORE_Kestrel__Certificates__Default__Password=<certificate_password> \
    -e ASPNETCORE_Kestrel__Certificates__Default__Path=/app/ssl/<certificate_filename>.pfx \
    --name tokengeneration \
    tokengeneration
