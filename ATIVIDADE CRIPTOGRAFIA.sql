
--CRIANDO A TABELA "TBL_CTRL_ACESSO"

CREATE TABLE TBL_CTRL_ACESSO (
    [Login] VARCHAR(50) NOT NULL,
    [Senha] VARBINARY(MAX),
    [Dica_senha] VARBINARY(MAX),
	CONSTRAINT PK_CTRL_ACESSO PRIMARY KEY ( [LOGIN] )
);
GO

--Criando a chave assimétrica
CREATE ASYMMETRIC KEY ChaveAssimetrica
WITH ALGORITHM = RSA_2048
ENCRYPTION BY PASSWORD = N'G@BRIEL48*';
GO

-- Criando função fn_encrypt (Função para criptografar a senha)
CREATE  FUNCTION dbo.fn_encrypt (
    @texto VARCHAR(MAX)
)
RETURNS VARBINARY(MAX)
AS
BEGIN
	Declare @senha INT = (select AsymKey_ID('ChaveAssimetrica'))
    DECLARE @Textocriptografado VARBINARY(MAX);

    -- Colocando valor e inserindo minha chave_assimetrica
    SET @Textocriptografado = EncryptByAsymKey(@senha, @texto);

    RETURN @Textocriptografado
END;
GO

 -- Conferindo a função criada acima e dando um exemplo de como ficou a senha G@BRIEL48* criptografada.

select dbo.FN_ENCRYPT('G@BRIEL48*')
GO

--Criando função de decriptografia (Função que decriptofra a senha metodo oposto da criptografia)
CREATE FUNCTION FN_DECRYPT(
		    @texto VARBINARY(MAX)
)
RETURNS VARCHAR(MAX)
AS 
BEGIN
	DECLARE @textoDecriptografado NVARCHAR(MAX);
	Declare @key INT = (select AsymKey_ID('ChaveAssimetrica'))

	SET @textoDecriptografado = CONVERT(VARCHAR,DecryptByAsymKey(@key,@texto, N'c'));

	return @textoDecriptografado;
END;
GO

--Conferindo a função de decriptografia
select dbo.FN_DECRYPT(dbo.FN_ENCRYPT('G@BRIEL48*'))
GO

--Criando função de criptografia 1-way HASH (Função que acrescenta algo a mais para a senha ficar mais forte)
ALTER FUNCTION fn_hash (
    @texto VARCHAR(MAX)
)
RETURNS VARBINARY(MAX) 
AS
BEGIN
    ---- Colocando uma informação a mais para melhorar a senha
    DECLARE @informacao2 VARCHAR(50) = 'FIT';

    ---- Juntando as duas informações para deixar a senha mais forte
    DECLARE @ValorAmbos VARCHAR(MAX) = @informacao2 + @texto;

    -- VARIAVEL DE HASH
    DECLARE  @ValorHash VARBINARY(64); 

    -- Calcular o hash do texto com segunda informação
    SET @ValorHash = HASHBYTES('SHA1',@ValorAmbos);

    RETURN  @ValorHash;
END;


GO

--Conferindo a função de criptografia de HASH
declare @senha varchar(max) = 'G@BRIEL48*'
select dbo.FN_HASH(@senha)
GO


--Colocando valores nas tabelas para testar o que foi criado:
INSERT INTO TBL_CTRL_ACESSO ( [LOGIN], [SENHA], [DICA_SENHA] )
VALUES ( 'LADOCHE', dbo.FN_HASH('senha'), dbo.FN_ENCRYPT('aquela lá') )
GO
--Dados colocados na tabela de forma criptografada 
select * from TBL_CTRL_ACESSO
GO


--Dados colocados na tabela decriptografado
select	[login]
		,[senha]
		,CONVERT(VARCHAR,dbo.FN_DECRYPT([dica_senha])) as [dica_senha] 
from TBL_CTRL_ACESSO
GO

ALTER PROCEDURE PR_LOGIN    
    @login VARCHAR(50),
    @senha VARCHAR(50),
    @autenticao BIT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @SenhaHash VARCHAR(64);

    -- Calculando o hash da senha inserida pelo usuario
    SET @SenhaHash = dbo.FN_HASH(@senha); 

	--Conferindo se o login e a senha é semelhante a dado cadastrado na tabela 
    IF EXISTS (SELECT 1 FROM TBL_CTRL_ACESSO WHERE Login = @login AND Senha = @SenhaHash)
    BEGIN
        SET @autenticao = 1; 
    END
    ELSE
    BEGIN
        SET @autenticao = 0; 
    END
END;


--Conferindo procedure de login
DECLARE @result BIT
	--autenticado
	EXEC PR_LOGIN 'LADOCHE', 'senha', @result OUTPUT
	SELECT CASE WHEN @result = 1 then 'Autenticado' else 'Sem autenticacão' end
	--Sem autenticação
	EXEC PR_LOGIN 'LADOCHE', 'senha errada', @result OUTPUT
	SELECT CASE WHEN @result = 1 then 'Autenticado' else 'Sem autenticacão' end
GO

-- CRIANDO PROCEDURE PARA ESQUECEU SENHA

ALTER PROCEDURE PR_ESQUECEU_SENHA
    @LOGIN VARCHAR(MAX),
    @result VARCHAR(MAX) OUTPUT
AS 
BEGIN
    SET NOCOUNT ON;

    DECLARE @CONSELHO VARBINARY(MAX);
    DECLARE @VALUE VARCHAR(MAX);

    -- Caso o usuario esqueceu a senha do cadastro nos criamos uma procedure para dar a dica da senha
    SELECT @CONSELHO = DICA_SENHA
    FROM TBL_CTRL_ACESSO
    WHERE Login = @LOGIN;

    IF @CONSELHO IS NOT NULL
    BEGIN
        -- Descriptografar a dica de senha
        SET @VALUE = dbo.FN_DECRYPT(@CONSELHO);

        SET @result = @VALUE;
    END
    ELSE
    BEGIN
    
        SET @result = NULL;
        RAISERROR ('Valor não encontrado', 16, 1);
    END
END;
GO


--Conferindo a procedure esqueceu senha
DECLARE @resultado VARCHAR(60) 
EXEC PR_ESQUECEU_SENHA 'LADOCHE', @resultado OUTPUT
SELECT 'Sua dica da senha é: "' + @resultado + '"'
GO








