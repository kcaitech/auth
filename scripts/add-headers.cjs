const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

const copyright = `/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

`;

async function addHeaderToFile(filePath) {
    try {
        const content = await readFile(filePath, 'utf8');
        if (!content.includes(copyright)) {
            await writeFile(filePath, copyright + content);
            console.log(`✅ Added header to ${filePath}`);
        } else {
            console.log(`⏭️  Skipped ${filePath} (header already exists)`);
        }
    } catch (err) {
        console.error(`❌ Error processing ${filePath}:`, err);
    }
}

const includes = ['admin-web', 'web', 'server', 'client', 'tools']
const excludes = ['assets', 'dist', 'node_modules']

function isExclude(filePath) {
    for (let i = 0, len = excludes.length; i < len; ++i) {
        if (filePath.endsWith(excludes[i])) return true
    }
    return false
}

function isCodeFile(filePath) {
    return filePath.endsWith('.ts') || filePath.endsWith('.vue') || filePath.endsWith('.go')
}

function findTypeScriptFiles(dir) {
    if (!fs.existsSync(dir)) return
    const files = fs.readdirSync(dir);
    
    files.forEach(file => {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        
        if (stat.isDirectory()) {
            if (!isExclude(filePath)) findTypeScriptFiles(filePath);
        } else if (isCodeFile(filePath)) {
            addHeaderToFile(filePath);
        }
    });
}

for (let i = 0, len = includes.length; i < len; ++i) {
    findTypeScriptFiles(path.resolve(__dirname, '..', includes[i]));
}