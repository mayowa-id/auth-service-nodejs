const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");

module.exports = function setupSwagger(app) {
    const options = {
        definition: {
            openapi: "3.0.0",
            info: {
                title: "Auth API",
                version: "1.0.0",
                description: "API documentation for authentication service",
            },
        },
        apis: ["./routes/auth.js", "./routes/admin.js"],
    };

    const specs = swaggerJsdoc(options);
    app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));
};
