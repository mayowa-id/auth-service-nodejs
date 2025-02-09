const client = require('../config/redis');

module.exports = async function (req, res, next) {
    try {
        const ip = req.ip;
        const key = `rate_limit_${ip}`;

        let requestCount = await client.get(key);

        if (!requestCount) {
            await client.setEx(key, 60, 1); // Set expiration to 60 seconds (1 min)
        } else if (requestCount >= 5) {
            const ttl = await client.ttl(key);
            return res.status(429).json({ 
                message: `Too many requests. Try again in ${ttl} seconds.` 
            });
        } else {
            await client.incr(key);
        }

        next();
    } catch (error) {
        console.error("Rate Limit Error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};
