# awstools

Provides a small set of commands to manage the most commonly used EC2 resources

[📚 Documentation](https://jordiprats.github.io/awstools/)

## configuration file

You can set some defaults using the **~/.awstools/config** file:

```
[aws]

region=us-west-2
useIP=PublicIpAddress
```

You can set the following options:

* **region**: Default region to use
* **useIP**: Default IP to show for EC2 instances (**PublicIpAddress** or **PrivateIpAddress**)

## Generate docs

If mkdocs doesn't recognize awstools, set **PYTHONPATH** to the base directory:

```
PYTHONPATH=$PWD mkdocs serve
```
