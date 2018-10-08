curl -s -N "https://api.github.com/repos/alecthomas/gometalinter/releases/latest" | # Get latest release from GitHub api
    grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^.//' # Get tag version number