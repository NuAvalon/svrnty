/**
 * Frozen demo SVRNTY public keys (no private material).
 * Generated once via openpgp `generateKey`; private keys discarded.
 * Fingerprints are `key.getFingerprint()` — Invariant-1: fingerprint ≡ H(public_key).
 *
 * Classical address-book rows must NOT use these (or any) fingerprints.
 */

export type SampleSvrntyPeer = {
  id: string;
  name: string;
  email: string;
  public_key: string;
  fingerprint: string;
  /** Open-visibility clique used for Peter’s peer-trust demo. */
  clique: boolean;
};

export const SAMPLE_SVRNTY_PEERS: SampleSvrntyPeer[] = [
  {
    id: "ada",
    name: "Ada Lovelace",
    email: "ada@example.invalid",
    clique: true,
    fingerprint: "1aaa4630e04f3b1ccf8ad54e6d42a8942b275e15",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JRYJKwYBBAHaRw8BAQdAdjBexWDqatDWAupNft3bPKfRVbTtV3+I\nqWAbMFbM4qHNIkFkYSBMb3ZlbGFjZSA8YWRhQGV4YW1wbGUuaW52YWxpZD7C\nwBMEExYKAIUFgmqUNCUDCwkHCZBtQqiUKydeFUUUAAAAAAAcACBzYWx0QG5v\ndGF0aW9ucy5vcGVucGdwanMub3JnBhGAgAHrsMc1E9/K5G9ZGTBpjc7tqzio\nKLlPQ8K/KMAFFQoIDgwEFgACAQIZAQKbAwIeARYhBBqqRjDgTzscz4rVTm1C\nqJQrJ14VAABwUgEAjpZyIXjzyAnspdXDzarboRI9k62UdBdo2KqdGMajnb0A\n/RDiwS0v+jwpHL3H+MLDwYf1vxVAsJBgbw21uZXMDtoPzjgEapQ0JRIKKwYB\nBAGXVQEFAQEHQBWdAYhwtr82GlC0ej9j1sUhc4wrP9oWXDU+BM/PPEkuAwEI\nB8K+BBgWCgBwBYJqlDQlCZBtQqiUKydeFUUUAAAAAAAcACBzYWx0QG5vdGF0\naW9ucy5vcGVucGdwanMub3JnFvrjEsjUhUzK177pBT6OgIFYv3kSkzQgcG9P\nZD1Wlg4CmwwWIQQaqkYw4E87HM+K1U5tQqiUKydeFQAAtD8BAMtDKyi9sKt6\nkxj3DuXEfloIhsZNbVLH7EW3+xN3SgeZAQDywTLQalvlBbG3zYVe9UwRCSw5\nGybGOxWC7bxKDfIMBA==\n=2g4T\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "grace",
    name: "Grace Hopper",
    email: "grace@example.invalid",
    clique: true,
    fingerprint: "4d6e67a08e48f25d8dd891b3fd3692891f0a10ee",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JRYJKwYBBAHaRw8BAQdAv4voeqnAigePSILLMnupFYt7To03b0ZR\nv5aLXYv1Uu7NJEdyYWNlIEhvcHBlciA8Z3JhY2VAZXhhbXBsZS5pbnZhbGlk\nPsLAEwQTFgoAhQWCapQ0JQMLCQcJkP02kokfChDuRRQAAAAAABwAIHNhbHRA\nbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmd0+RvFC7nIUon52REW62sdz8fnVUnU\nc/95qjh43cMb5gUVCggODAQWAAIBAhkBApsDAh4BFiEETW5noI5I8l2N2JGz\n/TaSiR8KEO4AAGFBAP9LUY3GUMifPnRrFJI1lBqY3po9NXtc+oC5a6OOnDaS\nHAD/f2q/B0Qct/qv4BlkcKzc3M4P2thIRiUEnIBryRNyJAnOOARqlDQlEgor\nBgEEAZdVAQUBAQdAQBR7vU9nBaE9/5ko/anY/UyAZc56qOAEzaNC916WIngD\nAQgHwr4EGBYKAHAFgmqUNCUJkP02kokfChDuRRQAAAAAABwAIHNhbHRAbm90\nYXRpb25zLm9wZW5wZ3Bqcy5vcmdC55HQdIRahtwIUjppX3ZFmuCpyODltd79\nwMThjzjs2wKbDBYhBE1uZ6COSPJdjdiRs/02kokfChDuAADKAAD/QZLknvcD\nTK/E+uXb3u7FtDC2wlqSYsQJhd06I5P8XGUA/3At50amIut+1Rek9q9obTh+\nu65XWxxik/0RAxfwcnsN\n=TrYt\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "margaret",
    name: "Margaret Hamilton",
    email: "margaret@example.invalid",
    clique: true,
    fingerprint: "888a60a3d61622e41c6d1427c9730a05aa478a0e",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JRYJKwYBBAHaRw8BAQdAJoiSDdRYhko12F05rlcl8UCKDtfycwT2\nvZgWckn3UXHNLE1hcmdhcmV0IEhhbWlsdG9uIDxtYXJnYXJldEBleGFtcGxl\nLmludmFsaWQ+wsATBBMWCgCFBYJqlDQlAwsJBwmQyXMKBapHig5FFAAAAAAA\nHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ5XpNpl00Mkhmy1cR2n7\nlOUCcn/JE9wJfPageM68GldIBRUKCA4MBBYAAgECGQECmwMCHgEWIQSIimCj\n1hYi5BxtFCfJcwoFqkeKDgAATFIBANc38PVPKfbpDVEpodlF+4OaBsNWfLtC\nzykgsy1+IGJvAP4+suKIP3SBgSL60nZIlAzHctgF7ykVFiqKYQoXIMlhA844\nBGqUNCUSCisGAQQBl1UBBQEBB0AfI2J9MSG98gRCydshDicS9euWhghpAGVp\nE7TrkRsEAgMBCAfCvgQYFgoAcAWCapQ0JQmQyXMKBapHig5FFAAAAAAAHAAg\nc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ0uEZxP2IUKYY34QQvfFzZlw\nVF34lc1gb5Dh6V3sH65CApsMFiEEiIpgo9YWIuQcbRQnyXMKBapHig4AANlB\nAQD8jJoqjA10SQtNqdWcRrrhx3u3EF9otTqwAuv3Dd4vqQEAzq7eQ/YVQRBb\nci7Axu4916f8pKDicytbehqrb9xB/QA=\n=y1q/\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "barbara",
    name: "Barbara Liskov",
    email: "barbara@example.invalid",
    clique: true,
    fingerprint: "cf8dafd4a9a7afa3552f790e2e57d05a7dbff3c9",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JhYJKwYBBAHaRw8BAQdAsANacBSdhRioGSeNxubx5m8fR6cxM7yk\nx71UHMKJiwLNKEJhcmJhcmEgTGlza292IDxiYXJiYXJhQGV4YW1wbGUuaW52\nYWxpZD7CwBMEExYKAIUFgmqUNCYDCwkHCZAuV9Bafb/zyUUUAAAAAAAcACBz\nYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3Jnq8mrBJhMH9kv7+OFe9cwkePc\nsdLfGJwt3vLv1IvfMMIFFQoIDgwEFgACAQIZAQKbAwIeARYhBM+Nr9Spp6+j\nVS95Di5X0Fp9v/PJAABR1QEAwqq44x8bCqkn3WnHAh0FEbkCR7/M6C3lTKBl\n03u+sMUBAKq0jey5RT3oRI8cG2t8r6uvTdRuEDMnCZTbFXQTgN0AzjgEapQ0\nJhIKKwYBBAGXVQEFAQEHQAbjb8O1rBMc//2uWrK78ZOx6VlXV3QeP9g3JHfW\nvyliAwEIB8K+BBgWCgBwBYJqlDQmCZAuV9Bafb/zyUUUAAAAAAAcACBzYWx0\nQG5vdGF0aW9ucy5vcGVucGdwanMub3Jnei4tD/7YHtfSdgNXti9e8fFng8pq\nx2oOScwZfdqc/40CmwwWIQTPja/Uqaevo1UveQ4uV9Bafb/zyQAAIBQBAMQW\ntiKxon4gW0l5FCog67KiMkvXVvY3+nJLq/Dwq3NhAPoCoQg05YkbTVOMTtdi\nZTXYIxsnXGR8MWPN+eyZMzC1CA==\n=57li\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "radia",
    name: "Radia Perlman",
    email: "radia@example.invalid",
    clique: true,
    fingerprint: "cecb1d386fcdb716971cf9534374d906a6dcd9b5",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JhYJKwYBBAHaRw8BAQdAdR/fpezKpCl3jkRqs/S7irkl/sPnQWMH\n+uqfAV4p2JXNJVJhZGlhIFBlcmxtYW4gPHJhZGlhQGV4YW1wbGUuaW52YWxp\nZD7CwBMEExYKAIUFgmqUNCYDCwkHCZBDdNkGptzZtUUUAAAAAAAcACBzYWx0\nQG5vdGF0aW9ucy5vcGVucGdwanMub3JnLXmUBhcCGhoMaBc5iRAQ7CCZTWOG\naXsZ9AqI0DeG9qIFFQoIDgwEFgACAQIZAQKbAwIeARYhBM7LHThvzbcWlxz5\nU0N02Qam3Nm1AAAewgD9ExMiuupO2shVeYTk7lRzMp2M0MKDJiN3pexYvd4Q\nMEABAPfjZ+/uaNwhHnXtozpmz0cN08J3zjhFFiO2cfi6ESwNzjgEapQ0JhIK\nKwYBBAGXVQEFAQEHQA2WcqRymmpy2+mRXu+DvMOU8/JksyD/nsYgLrDqERwc\nAwEIB8K+BBgWCgBwBYJqlDQmCZBDdNkGptzZtUUUAAAAAAAcACBzYWx0QG5v\ndGF0aW9ucy5vcGVucGdwanMub3JnCWm1qpIAQUNYYf1amyD9Qktl3n5SX95E\nG3BMQ19QevQCmwwWIQTOyx04b823Fpcc+VNDdNkGptzZtQAAb1IBAIaIOnQV\nqO2ZzrK2r/Um8tU1mihlSxMGsgdMxDGcmnc7AQD74eL1fCXcVYCxBmjsiV9m\nQYhoWVaGukCE6/OpQGc+Dg==\n=K0LX\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "joan",
    name: "Joan Clarke",
    email: "joan@example.invalid",
    clique: true,
    fingerprint: "4cb9fc5134f3b924cef425aafb514dae0d0b011a",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JhYJKwYBBAHaRw8BAQdA3+kZgBeywhM1hwmns97oPBkd13UuiNZr\nE1fizZW/R+3NIkpvYW4gQ2xhcmtlIDxqb2FuQGV4YW1wbGUuaW52YWxpZD7C\nwBMEExYKAIUFgmqUNCYDCwkHCZD7UU2uDQsBGkUUAAAAAAAcACBzYWx0QG5v\ndGF0aW9ucy5vcGVucGdwanMub3Jns9sQczXhZChSLHXy+PjhrPcUD4iwNh6l\ny8R6UDyEMG4FFQoIDgwEFgACAQIZAQKbAwIeARYhBEy5/FE087kkzvQlqvtR\nTa4NCwEaAAC29gEAq/6CR1OwTYUgs1uRbFx5MqX+5LdYkFuv8A4WcYt0gkcB\nAPQ22IB3hZG25EM3H/24CLvHyxNKAq/WbADjdgXyCRULzjgEapQ0JhIKKwYB\nBAGXVQEFAQEHQCvQFFXUO9ybEL7CX67xNaEqIIuEObStY5TJ/y2xHV18AwEI\nB8K+BBgWCgBwBYJqlDQmCZD7UU2uDQsBGkUUAAAAAAAcACBzYWx0QG5vdGF0\naW9ucy5vcGVucGdwanMub3JnTlxUN2wtE4YL5OpB4afdxRG/KkbJKE85BeDJ\nxNilpvYCmwwWIQRMufxRNPO5JM70Jar7UU2uDQsBGgAAzdcA/2pr906xFa5l\nyzzOB7QbOIKRZx3q2VrvkuDaFVUG4fJ6AQD+7JeJXPI6G3lku3MOzBFvXuVf\niNB2Xcir3k9khY88CQ==\n=ZQUq\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "jean",
    name: "Jean Bartik",
    email: "jean@example.invalid",
    clique: true,
    fingerprint: "95d67fd914ff243216ed5c1bddff67199cc0370c",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JhYJKwYBBAHaRw8BAQdAw/AewFxjJXndR8dWvVAhHiidctKWa+/B\n/B+89EJtMZvNIkplYW4gQmFydGlrIDxqZWFuQGV4YW1wbGUuaW52YWxpZD7C\nwBMEExYKAIUFgmqUNCYDCwkHCZDd/2cZnMA3DEUUAAAAAAAcACBzYWx0QG5v\ndGF0aW9ucy5vcGVucGdwanMub3Jnqb6hao39ghS9oFhEUsIDGylPNh4Zpbli\nd1C6YARp+gQFFQoIDgwEFgACAQIZAQKbAwIeARYhBJXWf9kU/yQyFu1cG93/\nZxmcwDcMAAAMxAD+Mn/LCXx7gXH/ZYeVf+AuC5pzWTRHSrHQ81FUM/kuz78A\n/1Rp1bPH+p9iabdsEvDesDrVmM8nLvGi0pd/oMYLejYDzjgEapQ0JhIKKwYB\nBAGXVQEFAQEHQEth0RhTpipu+EyoarRpQjZq4Pux7qImRxr8JEUQf7BxAwEI\nB8K+BBgWCgBwBYJqlDQmCZDd/2cZnMA3DEUUAAAAAAAcACBzYWx0QG5vdGF0\naW9ucy5vcGVucGdwanMub3JniIrGRZPax/byzjjRipY8GO02H9z0LTs3Nz8f\nkOxCTIsCmwwWIQSV1n/ZFP8kMhbtXBvd/2cZnMA3DAAA7ToA/0UI2CdNPasP\ntpcmOd6geqOJRtSby2/K1sKRttlnTG2uAP9sRFrg9oZD4wfn3iJqGKiK8ITR\nmXK2EP0USrf28L9NDw==\n=GPmu\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "sophie",
    name: "Sophie Germain",
    email: "sophie@example.invalid",
    clique: true,
    fingerprint: "c455adcae69d265e39752f3e24891c191e1c55bf",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JhYJKwYBBAHaRw8BAQdA04MRrJz6QUxW8ZDN747XI3Fw2m1WyExH\njVa2GiGvVZ7NJ1NvcGhpZSBHZXJtYWluIDxzb3BoaWVAZXhhbXBsZS5pbnZh\nbGlkPsLAEwQTFgoAhQWCapQ0JgMLCQcJkCSJHBkeHFW/RRQAAAAAABwAIHNh\nbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmdgRLLMAhLHQ1MwST3NC4G6Emgs\nRyBMs6YCb0Hy5luxjQUVCggODAQWAAIBAhkBApsDAh4BFiEExFWtyuadJl45\ndS8+JIkcGR4cVb8AAIyyAQCJr82MZSZ5pl6G4GLXnVh/IjEB4idPqjC2Rsu9\nVPiRUQEAm/UW3LTANUgK4cjVQ2cfq9xPqRC38UNWIBurqXm42gvOOARqlDQm\nEgorBgEEAZdVAQUBAQdAb0ADdU1F9fiOaBgw3Mw91ypqrVhwuT7SqaZT72yS\nBy4DAQgHwr4EGBYKAHAFgmqUNCYJkCSJHBkeHFW/RRQAAAAAABwAIHNhbHRA\nbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmecTfos3LUDVNNigfmCPMHajnu1Xc1y\n3yriLBCWPS1KRAKbDBYhBMRVrcrmnSZeOXUvPiSJHBkeHFW/AADAEgEA0A+x\nk1QS+3DpkiPrOigkrV9QStxtVctBzeFHNd0IKIkA/And0kSDwepTz/IXwCay\n9/iH7Kicb2mOSTdN77InPP8L\n=FfBW\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "alan",
    name: "Alan Turing",
    email: "alan@example.invalid",
    clique: false,
    fingerprint: "4c134c346efaf5bf5d2e94725d251489b3702a9c",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JhYJKwYBBAHaRw8BAQdAiEHajTqfkihklZYb2CSS/l5x9LCNr9k3\nK8Pxv3BviebNIkFsYW4gVHVyaW5nIDxhbGFuQGV4YW1wbGUuaW52YWxpZD7C\nwBMEExYKAIUFgmqUNCYDCwkHCZBdJRSJs3AqnEUUAAAAAAAcACBzYWx0QG5v\ndGF0aW9ucy5vcGVucGdwanMub3JnGz3NpQQ9j4yH5kiBncGvKxIWFI5TgDgE\nPGB/+efhNFEFFQoIDgwEFgACAQIZAQKbAwIeARYhBEwTTDRu+vW/XS6Ucl0l\nFImzcCqcAAC/nwD+MlZZlvbKKQuifw5dKjXabFMA/TMSAgUNXdnvGBSJlaoB\nAMpjgDN7QhPzAoUt37gDHP3nBEP8BkSRXQl/u8wMjT4EzjgEapQ0JhIKKwYB\nBAGXVQEFAQEHQO+RmkrNmTu76ZPX5whfY6vDMqCXh12//53/aAJV0+AfAwEI\nB8K+BBgWCgBwBYJqlDQmCZBdJRSJs3AqnEUUAAAAAAAcACBzYWx0QG5vdGF0\naW9ucy5vcGVucGdwanMub3JnArZ7GloVMqUlb68O16MYMfx9KuuoKewu48e6\nE1syTLYCmwwWIQRME0w0bvr1v10ulHJdJRSJs3AqnAAAxfUBAO+4FV3RMV3+\nujLt52Xqyst6IpFR0sa736ZfNVxZ1KQaAP9C9hMwpeZtlJwQ1+i/9+E5MzOD\n6BbRmThiEhSzcDHRAg==\n=z5ho\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
  {
    id: "dorothy",
    name: "Dorothy Vaughan",
    email: "dorothy@example.invalid",
    clique: false,
    fingerprint: "35cbbefc76d1e3a35a1338ca770563d750fe3596",
    public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEapQ0JhYJKwYBBAHaRw8BAQdArBsEbUgPD8L1NNcHyBw9K5AMofgBWSff\nERJfXjYLeezNKURvcm90aHkgVmF1Z2hhbiA8ZG9yb3RoeUBleGFtcGxlLmlu\ndmFsaWQ+wsATBBMWCgCFBYJqlDQmAwsJBwmQdwVj11D+NZZFFAAAAAAAHAAg\nc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ1OFqahBT5kZgsxuOCkWZiv8\naiub25w1Z5dokVtP/AUZBRUKCA4MBBYAAgECGQECmwMCHgEWIQQ1y778dtHj\no1oTOMp3BWPXUP41lgAAqE8A/i0uc6xpE++VR2tj6O25PNHPhu/JyYZzrsfM\nogR5y3LOAQDbTB6x0n/R/N5EFRSfhMZ14XdwEabi5j+MljOaIPkqD844BGqU\nNCYSCisGAQQBl1UBBQEBB0D6UNZVmhyvnEj9cxWoivFjcTy4QqnvmY4qQWUP\njadySwMBCAfCvgQYFgoAcAWCapQ0JgmQdwVj11D+NZZFFAAAAAAAHAAgc2Fs\ndEBub3RhdGlvbnMub3BlbnBncGpzLm9yZxjykanKvy5vD2unHfHxXpw5ccvm\n17gbgSNzWSYWwKEfApsMFiEENcu+/HbR46NaEzjKdwVj11D+NZYAACUCAP9b\nlhwq15MrkzmyNSy9DzCwMNjQU1uVV5ShLtskhtEauwEA4yJiq/t1yDci9x8Z\nWbYw3dI5fGpJqVT7Dw+So193lA4=\n=0I7Q\n-----END PGP PUBLIC KEY BLOCK-----\n",
  },
];

export const SAMPLE_SVRNTY_FPS = new Set(
  SAMPLE_SVRNTY_PEERS.map((p) => p.fingerprint.toLowerCase()),
);

export function sampleSvrntyByName(): Map<string, SampleSvrntyPeer> {
  return new Map(SAMPLE_SVRNTY_PEERS.map((p) => [p.name, p]));
}
