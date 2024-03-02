![Project Image](./cover.png)

# Food Delivery Web Application using Microservice Architecture with Nest.js, GraphQL, Next.js, Prisma

Welcome to the open-source Food Delivery Web Application series utilizing Microservice Architecture. This project aims to create a comprehensive Food Delivery Web Application employing Microservice Architecture. Separate applications will be built for Admin, User, Restaurant Owner, and Delivery Man. The entire project will be freely accessible, and this README covers the initial part, with more to come.

## Technology Used

Given the Microservice Architecture, it's challenging to enumerate all the exact technologies we plan to use. However, for an overview, we intend to employ Nest.js as the backend framework, GraphQL for Microservice connection gateway, Docker for containerizing our application, Prisma as the Database ORM, and AWS ECS for deployment, along with other AWS platforms. On the frontend, Next.js will be used for speed optimization and superior SEO. As this is the first part of our project, not all technologies have been finalized.

## How to run the project

Since its a mono repo nx application, you can run the project using the following command:

```bash
nx serve api-restuarants
```

```bash
nx serve api-users
```

```bash
nx serve api-admin
```

```bash
nx serve client
```
