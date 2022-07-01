# awstools

Provides a small set of commands to manage the most commonly used EC2 resources

[📚 Documentation](https://jordiprats.github.io/awstools/)

## configuration file

Create the file **~/.awstools/config** with the following content:

```
[aws]

region=us-west-2
useIP=PublicIpAddress
```

You can set the following options:

* region: Default region to use
* useIP: Default IP to show for EC2 instances (**PublicIpAddress** or **PrivateIpAddress**)

## Generate docs

```
PYTHONPATH=$PWD mkdocs serve
```
