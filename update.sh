#!/bin/sh

make
sudo systemctl stop chan
sudo cp -r chan web /srv/chan
sudo chown -R www-data:www-data /srv/chan/
sudo systemctl start chan
