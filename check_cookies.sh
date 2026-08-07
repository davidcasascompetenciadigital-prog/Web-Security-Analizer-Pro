#!/bin/bash
# Script para verificar cookies de un sitio web
# Uso: ./scripts/check_cookies.sh https://ejemplo.com

set -e

echo "=== 🔍 VERIFICANDO COOKIES ==="
echo ""

if [ -z "$1" ]; then
    echo "❌ Error: URL no especificada"
    echo "Uso: $0 <URL>"
    echo "Ejemplo: $0 https://www2.informaticacoslada.com"
    exit 1
fi

URL=$1

echo "📋 Analizando: $URL"
echo ""

curl -I "$URL" 2>/dev/null | grep -i "set-cookie" | while read -r cookie; do
    echo "🍪 Cookie: $cookie"
    echo "   ────────────────────"
    
    if echo "$cookie" | grep -qi "httponly"; then
        echo "   ✅ HttpOnly: PRESENTE"
    else
        echo "   ❌ HttpOnly: FALTA"
    fi
    
    if echo "$cookie" | grep -qi "secure"; then
        echo "   ✅ Secure: PRESENTE"
    else
        echo "   ❌ Secure: FALTA"
    fi
    
    if echo "$cookie" | grep -qi "samesite"; then
        echo "   ✅ SameSite: PRESENTE"
    else
        echo "   ❌ SameSite: FALTA"
    fi
    
    echo ""
done

echo "✅ Verificación completada"
