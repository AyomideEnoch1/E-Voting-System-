const keyManagementService = require('./key-management_service');

const tokenBlacklist = new Set();

class AuthMiddleware {
  authenticate(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer '))
        return res.status(401).json({ error: 'No token provided' });

      const token = authHeader.split(' ')[1];
      if (tokenBlacklist.has(token))
        return res.status(401).json({ error: 'Token has been invalidated' });

      const decoded = keyManagementService.verifyToken(token);
      req.user  = decoded;
      req.token = token;
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  authorize(...roles) {
    return (req, res, next) => {
      if (!req.user)
        return res.status(401).json({ error: 'Unauthorized — please log in' });
      if (!roles.includes(req.user.role))
        return res.status(403).json({ error: `Access denied — requires role: ${roles.join(' or ')}` });
      next();
    };
  }

  static blacklistToken(token) {
    tokenBlacklist.add(token);
    setTimeout(() => tokenBlacklist.delete(token), 8 * 60 * 60 * 1000);
  }

  // Instance proxy — lets callers do authMiddleware.blacklistToken(token)
  blacklistToken(token) {
    AuthMiddleware.blacklistToken(token);
  }
}

const instance = new AuthMiddleware();
module.exports = instance;
module.exports.blacklistToken = AuthMiddleware.blacklistToken;
