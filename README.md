# interview
Responsive web application with simple messaging and webrtc video calling for organize interviews.

# Features:
* Simple messaging (only text)
* Video calls based on webrtc technology
* Record and save streams to server
* View calls history
* Work in Mozilla Firefox 40+, Google Chrome 53+, IE Edge (not tested), also work in mobile browsers
* File or LDAP authentication and roles support

![Alt text](/screenshot1.png?raw=true "Screenshot 1")

![Alt text](/screenshot2.png?raw=true "Screenshot 2")

![Alt text](/screenshot3.png?raw=true "Screenshot 3")

# Install:
* Clone repository
* Run ./install.sh
* Run ./build_app.sh
* Run ./build_webapp.sh
* Create mysql database and user
* Create config.json file (see config.example.json)
* Run application ./interview ./config.json
