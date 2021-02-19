# Multistage, multi-arch docker build environmetn

## Building base:
```
docker buildx build --target=base --platform=linux/arm64,linux/amd64 --tag ockam/base:latest tools/docker/multiarch
```

## Building builder (automatically builds base too)
```
docker buildx build --target=builder --platform=linux/arm64,linux/amd64 --tag ockam/base:latest tools/docker/multiarch
```

## Running builder

This will only work if you've specified `--load` when building.

```
docker buildx build --load --target=builder --tag ockam/base:latest tools/docker/multiarch
docker run --rm -it -e HOST_USER_ID=$(id -u) -v $(pwd):/work ockam/builder:latest bash
```

If you want to run something that is not for your native platform, add `--platform=linux/arm64` for example.
It will be very slow because it uses qemu for translation.

## Releasing

Simply replace `--load` with `--push` in the above commands.

## Adding a new architecture

First, find out what $TARGETARCH gets set to by docker buildx.

```
cd tools/docker/multiarch
cp toolchain.cmake.amd64 toolchain.cmake.${TARGETARCH}
# now edit that file to change any arch specific things
cp versions_amd64.sh versions_${TARGETARCH}.sh
# now edit that file to point to any alternative platform names
# and also update the sha256 for all dependencies
```

After you've done that, you should be able to append your new platform to the list.

# Potential improvements

- [x] Fix permissions issues on Linux
- [ ] lot of speedups left on the table here
- [ ] Add elixir builder stage that does `MIX_ENV=prod mix release`
- [ ] Add elixir runner to the end that is based on alpine and uses only the artifacts from the elixir builder