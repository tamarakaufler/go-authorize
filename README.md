# go-authorize
Go implementation

## Synopsis

Implementation of a RESTful service with two APIs:

http://localhost:8080/authorize

    creates a JWT token and provides
    it in the autorization header and
    in the response

http://localhost:8080/users/{username}/articles

    example of using JWT verifying
    middleware, use of error message and code to identify encountered
    problems

Implementation uses:

- enum generation using go generate tool and stringer
- JWT creation and verification

- code quality ckeck using golangci-lint
- using Visual Studio REST Client extension to test the API

## Usage

- make all

or

- make run

# API Testing

Visual Studio IDE REST Client plugin is used to easily check the service
endpoints.

The plugin test setup is in `api-test/test.http` file. 

## Usage

1. start running the HTTP server using `make run`
2. go to `api-test/test.http` and run:

    a) POST {{scheme}}://{{hostname}}/authorize

    b) GET {{scheme}}://{{hostname}}/users/{{user}}/article
