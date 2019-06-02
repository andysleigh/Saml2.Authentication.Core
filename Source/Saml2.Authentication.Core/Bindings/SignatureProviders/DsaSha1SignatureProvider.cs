namespace Saml2.Authentication.Core.Bindings.SignatureProviders
{
    using System.Security.Cryptography;
    using System.Security.Cryptography.Xml;

    internal class DsaSha1SignatureProvider : ISignatureProvider
    {
        public string SignatureUri => SignedXml.XmlDsigDSAUrl;

        public byte[] SignData(AsymmetricAlgorithm key, byte[] data)
        {
            var sha1 = SHA1.Create();
            return ((DSA)key).CreateSignature(sha1.ComputeHash(data));
            //return ((DSA) key).SignData(data, HashAlgorithmName.SHA1);
        }

        public bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature)
        {
            var hash = new SHA1Managed().ComputeHash(data);
            return ((DSA)key).VerifySignature(hash, signature);
        }
    }
}