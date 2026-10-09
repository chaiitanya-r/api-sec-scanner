/**
 * @fileoverview JSDoc type definitions for OpenAPI parsing and endpoint normalization.
 */

/**
 * @typedef {'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'} HttpMethod
 */

/**
 * @typedef {'query' | 'header' | 'path'} ParameterLocation
 */

/**
 * @typedef {Object} NormalizedParameter
 * @property {string} name - Parameter name
 * @property {ParameterLocation} in - Location of parameter (query, header, path)
 * @property {string} type - Schema type (string, integer, number, boolean, etc.)
 * @property {boolean} [required] - Whether parameter is required
 * @property {*} [sampleValue] - Harmless benign sample value
 */

/**
 * @typedef {Object} NormalizedEndpoint
 * @property {string} path - Original endpoint path template (e.g., "/users/{id}")
 * @property {string} resolvedPath - Path with path parameters populated with harmless samples
 * @property {HttpMethod} method - HTTP method in uppercase
 * @property {boolean} requiresAuth - Whether endpoint requires authentication
 * @property {NormalizedParameter[]} parameters - List of supported query, header, path parameters
 * @property {string[]} expectedResponses - Sorted list of HTTP status code strings defined in spec
 * @property {string} [summary] - Brief operation summary if available
 * @property {string} [operationId] - Operation identifier if available
 */

export {};
