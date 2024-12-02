#!/usr/bin/env bash
# Place in .platform/hooks/postdeploy directory
sudo certbot -n -d turtleshelterprojectadmin.is404.net --nginx --agree-tos --email joefgerard@gmail.com
