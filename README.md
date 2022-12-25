# API IPTABLES
### Features

  - create new rule on iptables
  - get snapshot from current rules from iptables 
  - delete rule from iptable
  - update rule from iptable

### Tech

API uses a number of open source projects to work properly:

* [node.js] - evented I/O for the backend
* [Express] - fast node.js network app framework
* [Chil_proccess] - library from node.js to execute commands in shell

And of course API itself is open source with a [public repository][dill]
 on GitHub.
### Env file
Create .env file inside iptable directory.Structure from .env file
```.env
PORT={YOUR PORT TO RUN APP}
ENV=DEV
```
### Installation

Api requires [Node.js](https://nodejs.org/) v4+ to run.
Install the dependencies and devDependencies and start the server.
```sh
$ cd nodejs-waf
$ npm install
$ node src/app
```
License
----

MIT
