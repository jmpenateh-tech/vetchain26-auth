import express from "express";
import bcrypt from "bcrypt";
import pg from "pg";
import { db } from "./prisma/db.ts";
import { resolveSecret, signToken, verifyToken, bearer } from "./jwt.js";
import { createAudit, clientIp } from "./audit.js";
PLACEHOLDER_FULL_AUTH_INDEX