namespace IdentityProvider
{
    public interface IUserRepository
    {
        User GetUserBySubjectId(string subjectId);
    }
}