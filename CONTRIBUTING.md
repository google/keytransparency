# Contributing to the Key Transparency Server

We'd love for you to contribute to our source code! Here are the guidelines we'd like you to follow:

 - [Found an Issue?](#issue)
   - [Submission Prerequisites](#prereq)
   - [Submission Guidelines](#submit)
 - [Coding Rules](#rules)
 - [Signing the CLA](#cla)

## <a name="issue"></a> Found an Issue?
If you find a bug in the source code, you can help us by submitting an issue to
our [GitHub Repository][github]. Even better you can submit a Pull Request with
a fix.

### <a name="prereq"></a> Submission Prerequisites
Run the following commands to install the prerequisites needed to complete your
pull request submission:

```
go get -u github.com/golang/lint/golint
go get -u github.com/kisielk/errcheck
go get -u github.com/fzipp/gocyclo
go get -u github.com/gordonklaus/ineffassign
go get -u github.com/client9/misspell/cmd/misspell
```

### <a name="submit"></a> Submission Guidelines
Before you submit your pull request consider the following guidelines:

* Search [GitHub](https://github.com/google/keytransparency/pulls)
  for an open or closed Pull Request that relates to your submission. You don't
  want to duplicate effort.
* **Please sign our [Contributor License Agreement (CLA)](#cla)** before sending pull
  requests. We cannot accept code without this.
* Please be succinct. Create separate pull requests for separate bug fixes/features.
* Make your changes in a new git branch:

     ```shell
     git checkout -b my-fix-branch master
     ```

* Create your patch, **including appropriate test cases**.
* Follow our [Coding Rules](#rules).
* Run `make` to build your changes and ensure the build is not broken.
* Run `go fmt` to correct any styling errors in the code
* Run `go test` to run the full test suite.
* Run `make presubmit` to ensure the patch includes healthy go code.

* Push your branch to GitHub:

    ```shell
    git push origin my-fix-branch
    ```

* In GitHub, send a pull request to `google:master`.
* If we suggest changes then
  * Make the required updates.
  * Re-run the test suite and build to ensure the code is still healthy.
  * Rebase your branch and force push to your GitHub repository (this will update your Pull Request):

    ```shell
    git rebase master -i
    git push -f
    ```

That's it! Thank you for your contribution!

#### After your pull request is merged

After your pull request is merged, you can safely delete your branch and pull the changes
from the main (upstream) repository:

* Delete the remote branch on GitHub either through the GitHub web UI or your local shell as follows:

    ```shell
    git push origin --delete my-fix-branch
    ```

* Check out the master branch:

    ```shell
    git checkout master -f
    ```

* Delete the local branch:

    ```shell
    git branch -D my-fix-branch
    ```

* Update your master with the latest upstream version:

    ```shell
    git pull --ff upstream master
    ```

## <a name="rules"></a> Coding Rules
To ensure consistency throughout the source code, keep these rules in mind as you are working:

* All features or bug fixes **must be tested**.
* All public API methods **must be documented**.

## <a name="cla"></a> Signing the CLA

Please sign our Contributor License Agreement (CLA) before sending pull requests. For any code
changes to be accepted, the CLA must be signed. It's a quick process, we promise!

* For individuals we have a [simple click-through form][individual-cla].
* For corporations we'll need you to
  [print, sign and one of scan+email, fax or mail the form][corporate-cla].

[corporate-cla]: http://code.google.com/legal/corporate-cla-v1.0.html
[github]: https://github.com/google/keytransparency
[individual-cla]: http://code.google.com/legal/individual-cla-v1.0.html
[issues]: https://github.com/google/keytransparency/issues
