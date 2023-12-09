# Backend, authpage and deployment

See the [book](https://dsavdodeka.nl/book) for detailed instructions.


## Command shortcuts

See [this page](https://dsavdodeka.nl/book/setup/docker.html#shortcuts) for more details.

The scripts are all in the root directory, but you can call them using `../` if you are in a subdirectory and they'll still work. Make sure [you've installed Nu](https://dsavdodeka.nl/book/setup/docker.html#installing-nushell).

### Running the development databases

Start (this will also pull the images, so make sure you're logged in with `docker login ghcr.io`): 

```
nu dev.nu upp
```

Stop:

```
nu dev.nu down
```

On Linux/macOS:

```
nu dev.nu up
```

### Testing and checking the backend

```
nu test.nu backend
```